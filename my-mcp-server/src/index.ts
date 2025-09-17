import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

interface SabreAuthResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

type CachedToken = {
  token: string;
  expiresAt: number;
};

const credentialCacheStore: Record<string, CachedToken> = {};

export interface FlightSegment {
  RPH: string;
  DepartureDateTime: string;
  OriginLocation: string;
  DestinationLocation: string;
}

export interface PassengerInfo {
  Quantity: number;
  Code: string;
  VoluntaryChangesMatch?: string;
}

export function createBargainFinderMaxRequest(
  pseudoCityCode: string,
  flightSegments: FlightSegment[],
  passengers: PassengerInfo[]
) {
  return {
    OTA_AirLowFareSearchRQ: {
      Version: "4.3.0",
      POS: {
        Source: [
          {
            PseudoCityCode: pseudoCityCode,
            RequestorID: {
              Type: "1",
              ID: "1",
              CompanyName: {
                Code: "TN",
                content: "TN"
              }
            }
          }
        ]
      },
      OriginDestinationInformation: flightSegments.map((seg, index) => ({
        RPH: seg.RPH || String(index + 1),
        DepartureDateTime: seg.DepartureDateTime,
        OriginLocation: {
          LocationCode: seg.OriginLocation
        },
        DestinationLocation: {
          LocationCode: seg.DestinationLocation
        }
      })),
      TravelPreferences: {
        VendorPref: [
          {
            Code: "TR",
            PreferLevel: "Unacceptable"
          },
          {
            Code: "JQ",
            PreferLevel: "Unacceptable"
          }
        ],
        Baggage: {
          RequestType: "A",
          Description: true
        }
      },
      TravelerInfoSummary: {
        SeatsRequested: [passengers.reduce((sum, p) => sum + p.Quantity, 0)],
        AirTravelerAvail: [
          {
            PassengerTypeQuantity: passengers.map(p => ({
              Quantity: p.Quantity,
              Code: p.Code,
              TPA_Extensions: p.VoluntaryChangesMatch
                ? { VoluntaryChanges: { Match: p.VoluntaryChangesMatch } }
                : undefined
            }))
          }
        ]
      },
      TPA_Extensions: {
        IntelliSellTransaction: {
          RequestType: {
            Name: "50ITINS"
          }
        }
      }
    }
  };
}

const credentialCache = {
  async getToken(cacheKey: string, fetchToken: () => Promise<{ AccessToken: string, expires_in: number }>) {
    const cached = credentialCacheStore[cacheKey];

    if (cached && Date.now() < cached.expiresAt) {
      return { AccessToken: cached.token, expires_in: (cached.expiresAt - Date.now()) / 1000 };
    }

    const result = await fetchToken();

    credentialCacheStore[cacheKey] = {
      token: result.AccessToken,
      expiresAt: Date.now() + result.expires_in * 1000
    };

    return result;
  },
};

async function restAuthenticate(pcc: string, epr: string, password: string, authEndpoint: URL) : Promise<{ AccessToken: string, expires_in: number }>{

  const sabreDomain = "AA";
  const grantType = "grant_type";
  const clientCredentials = "client_credentials";

  const encodedClientId = Buffer.from(`V1:${epr}:${pcc}:${sabreDomain}`).toString("base64");
  const encodedPassword = Buffer.from(password).toString("base64");
  const basicAuth = `Basic ${Buffer.from(`${encodedClientId}:${encodedPassword}`).toString("base64")}`;

  const formBody = new URLSearchParams({ [grantType]: clientCredentials });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);

  const response = await fetch(authEndpoint, {
    method: "POST",
    headers: {
      "Authorization": basicAuth,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: formBody.toString(),
    signal: controller.signal
  });

  clearTimeout(timeout);

  if (!response.ok) {
    throw new Error(`Authentication failed: ${response.status} - ${await response.text()}`);
  }

  const data: SabreAuthResponse = await response.json();

  return { AccessToken: data.access_token, expires_in: data.expires_in };
}

async function searchFlights(
  bargainFinderMaxRequest: any,
  accessToken: string,
  searchEndpoint: URL,
  retryCount: number = 1
): Promise<Response> {
  const jsonContent = JSON.stringify(bargainFinderMaxRequest);

  let lastError: any = null;

  for (let attempt = 0; attempt <= retryCount; attempt++) {
    try {
      const response = await fetch(searchEndpoint, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: jsonContent,
      });

      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status} - ${await response.text()}`);
      }

      return response;
    } catch (error) {
      lastError = error;
      if (attempt === retryCount) throw error;

      await new Promise(res => setTimeout(res, 1000));
    }
  }

  throw lastError;
}

// Define our MCP agent with tools
export class MyMCP extends McpAgent<Env> {
  server = new McpServer({
    name: "Authless Calculator",
    version: "1.0.0",
  });

  async init() {

    // Rest Authentication tool
    this.server.tool(
      "getRestAccessToken",
      {},
      async () => {
        const options = {
          RestBaseUrl: this.env.REST_URL,
          Password: this.env.GDS_PASSWORD,
          PCC: this.env.GDS_PCC,
          EmployeeProfileRecord: this.env.GDS_AGENT_CODE,
        };

        const AuthEndpoint = new URL(
          this.env.SABRE_AUTH_ENDPOINT,
          this.env.REST_URL
        );
        const cacheKey = `SabreRestAuth:${options.RestBaseUrl}-${options.PCC}-${options.EmployeeProfileRecord}-${options.Password}`;

        const authResponse = await credentialCache.getToken(
          cacheKey,
          () =>
            restAuthenticate(
              options.PCC,
              options.EmployeeProfileRecord,
              options.Password,
              AuthEndpoint
            )
        );

       return {
          content: [
            {
              type: "text",
              text: authResponse.AccessToken,
            },
          ],
        };
      }
    );

    //Air Price Monitor
    this.server.tool(
      "AirPriceMonitor",
       {        
        pseudoCityCode: z.string(),
        departureDateTimeOutbound: z.string(),
        departureDateTimeReturn: z.string(),
        originLocation: z.string(),
        destinationLocation: z.string(),
        passengerTypeCode: z.string(),
        passengerQuantity: z.number().default(1),
       },
       async ({
        pseudoCityCode,
        departureDateTimeOutbound,
        departureDateTimeReturn,
        originLocation,
        destinationLocation,
        passengerTypeCode,
        passengerQuantity
        }) => {

        const options = {
          RestBaseUrl: this.env.REST_URL,
          Password: this.env.GDS_PASSWORD,
          PCC: this.env.GDS_PCC,
          EmployeeProfileRecord: this.env.GDS_AGENT_CODE,
        };

        const AuthEndpoint = new URL(
          this.env.SABRE_AUTH_ENDPOINT,
          this.env.REST_URL
        );

        const BFMEndPoint = new URL(
        this.env.SABRE_SEARCH_ENDPOINT,
        this.env.REST_URL
      );

        const cacheKey = `SabreRestAuth:${options.RestBaseUrl}-${options.PCC}-${options.EmployeeProfileRecord}-${options.Password}`;

        const authResponse = await credentialCache.getToken(
          cacheKey,
          () =>
            restAuthenticate(
              options.PCC,
              options.EmployeeProfileRecord,
              options.Password,
              AuthEndpoint
            )
        );

        const flightSegments = [
          {
            RPH: "1",
            DepartureDateTime: departureDateTimeOutbound,
            OriginLocation: originLocation,
            DestinationLocation: destinationLocation,
          },
          {
            RPH: "2",
            DepartureDateTime: departureDateTimeReturn,
            OriginLocation: destinationLocation,
            DestinationLocation: originLocation,
          },
        ];

        const passengers = [
          {
            Quantity: passengerQuantity ?? 1,
            Code: passengerTypeCode,
            VoluntaryChangesMatch: "Info",
          },
        ];

        const bfmRequest = createBargainFinderMaxRequest(
          pseudoCityCode,
          flightSegments,
          passengers
        );

        const response = await searchFlights(
          bfmRequest,
          authResponse.AccessToken,
          BFMEndPoint,
          1
        )
        
        const result = await response.text();

        return {
            content: [
              {
               type: "text",
               text: result,
              },
            ],
          };
      });
  }
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === "/sse" || url.pathname === "/sse/message") {
      return MyMCP.serveSSE("/sse").fetch(request, env, ctx);
    }

    if (url.pathname === "/mcp") {
      return MyMCP.serve("/mcp").fetch(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
};