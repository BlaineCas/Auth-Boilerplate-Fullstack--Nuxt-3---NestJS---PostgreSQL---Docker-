import {
  Injectable,
  ExecutionContext,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleOAuthGuard extends AuthGuard('google') {
  // Extends AuthGuard and specifies the 'google' strategy
  private readonly logger = new Logger(GoogleOAuthGuard.name);

  // The canActivate method is inherited and will initiate the OAuth flow
  // It is important that sessions are properly configured if Passport uses them
  // (although for stateless APIs with JWT, sessions may not be needed after obtaining the token)
  async canActivate(context: ExecutionContext): Promise<boolean> {
    this.logger.debug('GoogleOAuthGuard canActivate called.');
    const activate = (await super.canActivate(context)) as boolean; // Initiates the OAuth flow
    if (activate) {
      const request = context.switchToHttp().getRequest();
      this.logger.debug(
        'GoogleOAuthGuard attempting to log in session (if session support is enabled).',
      );
      await super.logIn(request); // Required for Passport to properly handle the flow, especially if sessions are enabled
    }
    return activate;
  }

  handleRequest(err, user, info, context: ExecutionContext) {
    if (err || !user) {
      this.logger.error(
        `GoogleOAuthGuard authentication failed: ${info?.message || err?.message}`,
        err?.stack,
      );
      // Redirecting to an error page on the client side should be handled in the controller after the guard throws the exception
      throw (
        err ||
        new UnauthorizedException(
          info?.message || 'Google authentication failed.',
        )
      );
    }
    this.logger.debug(
      `GoogleOAuthGuard authentication successful for user (from Google): ${user.email}`,
    );
    return user;
  }
}
