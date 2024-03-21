/*
------------------------------------------------------------------------------ 
This code was generated by Amplication. 
 
Changes to this file will be lost if the code is regenerated. 

There are other ways to to customize your code, see this doc to learn more
https://docs.amplication.com/how-to/custom-code

------------------------------------------------------------------------------
  */
import { UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { passportJwtSecret } from "jwks-rsa";
import { ExtractJwt, Strategy } from "passport-jwt";
import { KeycloakPayload } from "./types";
import { UserInfo } from "../../UserInfo";
import { UserService } from "src/user/user.service";

export class JwtStrategyBase extends PassportStrategy(Strategy) {
  constructor(
    protected readonly configService: ConfigService,
    protected readonly userService: UserService
  ) {
    const url = configService.get<string>("KEYCLOAK_URL");
    const realm = configService.get<string>("KEYCLOAK_REALM");
    const issuerURL = `${url}/realms/${realm}`;

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Extract JWT from the Authorization header
      issuer: issuerURL,

      secretOrKeyProvider: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `${issuerURL}/protocol/openid-connect/certs`,
      }),
    });
  }

  // Validate the received JWT and construct the user object out of the decoded token.
  async validateBase(payload: KeycloakPayload): Promise<UserInfo | null> {
    const user = await this.userService.user({
      where: {
        email: payload.email,
      },
    });

    return user ? { ...user, roles: user?.roles as string[] } : null;
  }
}