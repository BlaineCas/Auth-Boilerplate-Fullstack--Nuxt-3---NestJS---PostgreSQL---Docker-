import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import {
  Strategy as GoogleOAuthStrategy,
  VerifyCallback,
  Profile,
} from 'passport-google-oauth20'; // Alias to avoid naming conflict

@Injectable()
export class GoogleStrategy extends PassportStrategy(
  GoogleOAuthStrategy,
  'google',
) {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID') as string,
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET') as string,
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string, // Google may return a refresh token on first login if offline access is requested
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, name, emails, photos } = profile;
    this.logger.debug(`GoogleStrategy validating profile for Google ID: ${id}`);
    this.logger.verbose(`Google Profile Raw: ${JSON.stringify(profile)}`);

    if (!emails || emails.length === 0 || !emails[0].value) {
      this.logger.error('Google profile did not return a valid email address.');
      return done(
        new Error('Could not retrieve email address from Google.'),
        false,
      );
    }

    const user = {
      googleId: id,
      email: emails[0].value,
      firstName: name?.givenName || emails[0].value.split('@')[0],
      lastName: name?.familyName || '',
      avatarUrl: photos && photos.length > 0 ? photos[0].value : null,
      // We don't pass Google's accessToken or refreshToken further here,
      // since AuthService will generate our own tokens (access and refresh).
    };
    this.logger.log(
      `User data extracted from Google profile: ${JSON.stringify({ email: user.email, googleId: user.googleId })}`,
    );
    done(null, user);
  }
}
