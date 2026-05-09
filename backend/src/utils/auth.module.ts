import { Module } from "@nestjs/common";
import { authProvider } from "./auth";

@Module({
  providers: [authProvider],
  exports: [authProvider],
})
export class AuthConfigModule {}
