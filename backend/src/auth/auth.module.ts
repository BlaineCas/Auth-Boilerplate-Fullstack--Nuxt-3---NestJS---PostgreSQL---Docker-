import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module'; // Imports UsersModule to use UsersService
import { PassportModule } from '@nestjs/passport'; // Module for integrating Passport.js strategies
import { JwtModule } from '@nestjs/jwt'; // Module for working with JSON Web Tokens
import { ConfigModule, ConfigService } from '@nestjs/config'; // For accessing environment variables
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';

@Module({
  imports: [
    UsersModule, // Makes UsersService available for injection into AuthService
    PassportModule.register({ defaultStrategy: 'jwt' }), // Registers PassportModule, specifying 'jwt' as the default strategy
    JwtModule.registerAsync({
      // Registers JwtModule asynchronously to inject ConfigService
      imports: [ConfigModule], // Imports ConfigModule to access environment variables
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'), // The secret key for signing JWT tokens
        signOptions: { expiresIn: configService.get<string>('JWT_EXPIRES_IN') }, // The expiration time of the tokens
      }),
      inject: [ConfigService], // Injects ConfigService into useFactory
    }),
    ConfigModule, // Ensure that ConfigModule is available (it could be global in AppModule)
    // MailModule, // If you plan to add a module for sending emails
  ],
  providers: [
    AuthService, // The service that contains the authentication logic
    LocalStrategy, // Provider for the local strategy
    JwtStrategy, // Provider for the JWT strategy
    GoogleStrategy, // Provider for the Google strategy
  ],
  controllers: [AuthController], // The controller that exposes authentication endpoints
  exports: [AuthService, JwtModule, PassportModule], // Exports AuthService and JwtModule to be used in other parts of the application if needed
})
export class AuthModule {}
