import {
  IsEmail,
  IsString,
  MinLength,
  IsOptional,
  IsEnum,
} from 'class-validator';
import { UserRole } from '../entities/user.entity';

// Data Transfer Object for creating a new user
export class CreateUserDto {
  @IsEmail({}, { message: 'The email must be a valid address.' }) // Validates if it's a valid email
  email: string;

  @IsOptional() // The password is optional, e.g., for OAuth
  @IsString({ message: 'The password must be a string.' })
  @MinLength(8, { message: 'The password must have at least 8 characters.' })
  password?: string;

  @IsOptional()
  @IsString({ message: 'The first name must be a string.' })
  firstName?: string;

  @IsOptional()
  @IsString({ message: 'The last name must be a string.' })
  lastName?: string;

  @IsOptional()
  @IsString()
  googleId?: string;

  @IsOptional()
  @IsString({
    message: 'The avatar URL must be a string.',
  })
  avatarUrl?: string;

  @IsOptional()
  @IsEnum(UserRole, {
    message: 'The role must be a valid value (user, admin).',
  }) // Validates if the role is one of the defined values in UserRole
  role?: UserRole = UserRole.USER; // Default role

  @IsOptional()
  isEmailVerified?: boolean = false; // By default, the email is not verified
}
