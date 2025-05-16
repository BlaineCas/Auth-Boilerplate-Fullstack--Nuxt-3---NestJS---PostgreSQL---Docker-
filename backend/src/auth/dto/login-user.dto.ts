import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginUserDto {
  @IsEmail({}, { message: 'Email must be a valid address.' })
  email: string;

  @IsString({ message: 'Password is required.' })
  @MinLength(1, { message: 'Password cannot be empty.' })
  password: string;
}
