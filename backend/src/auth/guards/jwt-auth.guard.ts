import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  // Extends AuthGuard and specifies the 'jwt' strategy
  private readonly logger = new Logger(JwtAuthGuard.name);

  canActivate(context: ExecutionContext) {
    this.logger.debug('JwtAuthGuard canActivate called.');
    return super.canActivate(context);
  }

  handleRequest(err, user, info, context: ExecutionContext) {
    // `info` may contain error details, e.g., TokenExpiredError, JsonWebTokenError
    if (err || !user) {
      let message = 'You are not authorized.';
      if (info instanceof Error) {
        message =
          info.message === 'No auth token'
            ? 'Missing authentication token.'
            : info.message === 'jwt expired'
              ? 'Session has expired. Please log in again.'
              : 'Invalid token.';
        this.logger.warn(
          `JwtAuthGuard authentication failed: ${info.name} - ${info.message}`,
        );
      } else if (info && typeof info.message === 'string') {
        message = info.message;
        this.logger.warn(`JwtAuthGuard authentication failed: ${info.message}`);
      } else if (err) {
        message = err.message;
        this.logger.warn(`JwtAuthGuard authentication error: ${err.message}`);
      } else {
        this.logger.warn(`JwtAuthGuard authentication failed: Unknown reason.`);
      }
      throw err || new UnauthorizedException(message);
    }
    this.logger.debug(
      `JwtAuthGuard authentication successful for user ID: ${user.id}`,
    );
    return user; // Returns the user if the JWT token is valid
  }
}
