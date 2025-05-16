import {
  Injectable,
  ExecutionContext,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
  // Extends AuthGuard and specifies the 'local' strategy
  private readonly logger = new Logger(LocalAuthGuard.name);

  // Optional: override canActivate to add logic before strategy activation
  canActivate(context: ExecutionContext) {
    this.logger.debug('LocalAuthGuard canActivate called.');
    // You can add logic here, for example, to check if the request is of a certain type
    return super.canActivate(context); // Calls the base implementation
  }

  // Optional: override handleRequest to customize error handling or the result
  handleRequest(err, user, info, context: ExecutionContext) {
    if (err || !user) {
      this.logger.warn(
        `LocalAuthGuard authentication failed: ${info?.message || err?.message}`,
      );
      throw (
        err ||
        new UnauthorizedException(info?.message || 'Authentication failed.')
      );
    }
    this.logger.debug(
      `LocalAuthGuard authentication successful for user: ${user.email}`,
    );
    return user; // Returns the user if authentication succeeds
  }
}
