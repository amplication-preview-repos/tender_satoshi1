import { Injectable } from "@nestjs/common";
import { JwtStrategyBase } from "./base/jwt.strategy.base";
import { ConfigService } from "@nestjs/config";
import { KeycloakPayload } from "./base/types";
import { IAuthStrategy } from "../IAuthStrategy";
import { UserInfo } from "../UserInfo";
import { UserService } from "src/user/user.service";

@Injectable()
export class JwtStrategy extends JwtStrategyBase implements IAuthStrategy {
  constructor(
    protected readonly configService: ConfigService,
    protected readonly userService: UserService
  ) {
    super(configService, userService);
  }

  async validate(payload: KeycloakPayload): Promise<UserInfo> {
    const validatedUser = await this.validateBase(payload);

    // Validate if the user is authorized to the specified client
    if (payload.azp !== this.configService.get<string>("KEYCLOAK_CLIENT_ID")) {
      throw new Error("Invalid token");
    }

    // If the entity is valid, return it
    if (validatedUser) {
      if (
        !Array.isArray(validatedUser.roles) ||
        typeof validatedUser.roles !== "object" ||
        validatedUser.roles === null
      ) {
        throw new Error("ENTITY roles is not a valid value");
      }

      return validatedUser;
    }

    // Otherwise, make a new entity and return it
    const userFields = payload;
    const defaultData = {
      email: userFields.email,
      password: "20c5e532be4729a8a724",
      roles: ["user"],
      username: "admin",
    };

    const newUser = await this.userService.createUser({
      data: defaultData,
    });

    return { ...newUser, roles: newUser?.roles as string[] };
  }
}
