import {
  Controller,
  Post,
  Body,
  UseGuards,
  Request,
  Get,
  Query,
  Res,
  HttpStatus,
  HttpCode,
  Logger,
  BadRequestException,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GoogleOAuthGuard } from './guards/google-oauth.guard';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  private readonly CLIENT_URL: string;

  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {
    this.CLIENT_URL = this.configService.get<string>('CLIENT_URL') as string;
    this.logger.log(`Client URL initialized to: ${this.CLIENT_URL}`);
  }

  // Needs refactoring !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

  @Post('register')
  async register(
    @Body() registerUserDto: RegisterUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    this.logger.log(
      `POST /auth/register called with email: ${registerUserDto.email}`,
    );
    const result = await this.authService.register(registerUserDto);
    // Consider sending the refresh token in an HttpOnly cookie
    // res.cookie('refresh_token', result.refreshToken, { httpOnly: true, secure: false, sameSite: 'lax', path: '/' });

    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(
    @Request() req,
    @Body() loginUserDto: LoginUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    this.logger.log(`POST /auth/login called for user: ${req.user.email}`);
    const result = await this.authService.login(req.user);

    // Send the refresh token in an HttpOnly, Secure cookie
    // res.cookie('refresh_token', result.refreshToken, {
    //   httpOnly: true,
    //   secure: this.configService.get<string>('NODE_ENV') === 'production', // true in production
    //   sameSite: 'lax', // 'lax' or 'none' (with Secure) if cross-site is needed
    //   path: '/api/auth', // Limit the cookie path
    //   expires: new Date(Date.now() + this.authService['parseExpiry'](this.configService.get<string>('JWT_REFRESH_EXPIRES_IN')) * 1000),
    // });
    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  async googleAuth(@Request() req) {
    this.logger.log('GET /auth/google called, redirecting to Google...');
  }

  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  async googleAuthRedirect(@Request() req, @Res() res: Response) {
    this.logger.log(
      `GET /auth/google/callback called for user: ${req.user?.email}`,
    );
    const result = await this.authService.googleLogin(req.user);

    if (result.accessToken && result.user) {
      this.logger.log(
        `Google login successful for ${result.user.email}. Redirecting to client.`,
      );
      // res.cookie('refresh_token', result.refreshToken, { httpOnly: true, secure: false, sameSite: 'lax', path: '/' });
      const userJson = encodeURIComponent(JSON.stringify(result.user)); // Only send safe data
      // Also send the refresh token in the query param for testing, but ideally it should be in a cookie
      res.cookie('refresh_token', result.refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      return res.redirect(
        `${this.CLIENT_URL}/login-success?token=${result.accessToken}&user=${userJson}`,
      );
    } else {
      this.logger.error(
        'Google login failed after callback. Redirecting to client failure page.',
      );
      return res.redirect(
        `${this.CLIENT_URL}/login-failure?error=google_auth_failed`,
      );
    }
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    this.logger.log(`POST /auth/refresh called.`);

    const refreshToken = (req as any).cookies?.refresh_token;

    if (!refreshToken) {
      throw new BadRequestException('Refresh token is missing.');
    }

    const result = await this.authService.refreshToken(refreshToken);

    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return {
      accessToken: result.accessToken,
    };
  }

  // New endpoint for logout
  @UseGuards(JwtAuthGuard) // Requires a valid access token to identify the user
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Request() req, @Res({ passthrough: true }) res: Response) {
    const userId = req.user.id; // JwtAuthGuard populates req.user
    this.logger.log(`POST /auth/logout called by user ID: ${userId}`);
    await this.authService.logout(userId);
    // Clear the refresh_token cookie
    res.clearCookie('refresh_token', { path: '/' });
    return { message: 'Logout successful.' };
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  getProfile(@Request() req) {
    this.logger.log(`GET /auth/profile called by user ID: ${req.user.id}`);
    return req.user;
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    this.logger.log(
      `POST /auth/forgot-password called for email: ${forgotPasswordDto.email}`,
    );
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    this.logger.log(`POST /auth/reset-password called with token.`);
    return this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.newPassword,
    );
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string, @Res() res: Response) {
    this.logger.log(`GET /auth/verify-email called with token.`);
    if (!token) {
      this.logger.warn('Verify email attempt with no token.');
      return res.redirect(
        `${this.CLIENT_URL}/email-verification-failed?error=${encodeURIComponent('Missing verification token.')}`,
      );
    }
    try {
      const result = await this.authService.verifyEmail(token);
      this.logger.log(
        `Email verification successful for user: ${result.user?.email}. Redirecting.`,
      );
      // res.cookie('refresh_token', result.refreshToken, { httpOnly: true, secure: false, sameSite: 'lax', path: '/' });
      const userJson = result.user
        ? encodeURIComponent(JSON.stringify(result.user))
        : '';
      res.cookie('refresh_token', result.refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      return res.redirect(
        `${this.CLIENT_URL}/email-verified?message=${encodeURIComponent(result.message)}&token=${result.accessToken}&user=${userJson}`,
      );
    } catch (error) {
      this.logger.error(
        `Email verification failed: ${error.message}. Redirecting.`,
      );
      return res.redirect(
        `${this.CLIENT_URL}/email-verification-failed?error=${encodeURIComponent(error.message)}`,
      );
    }
  }

  @Post('resend-verification-email')
  @HttpCode(HttpStatus.OK)
  async resendVerificationEmail(@Body('email') email: string) {
    this.logger.log(
      `POST /auth/resend-verification-email called for email: ${email}`,
    );
    if (!email) {
      this.logger.warn(
        'Resend verification email attempt with no email provided.',
      );
      throw new BadRequestException('Email address is required.');
    }
    return this.authService.resendVerificationEmail(email);
  }
}
