import {
  IsString,
  MinLength,
  MaxLength,
  Matches,
  IsNotEmpty,
} from 'class-validator';

export class ResetPasswordDto {
  @IsNotEmpty({ message: 'Reset token is required.' })
  @IsString()
  token: string;

  @IsString({ message: 'New password must be a string.' })
  @MinLength(8, { message: 'New password must be at least 8 characters long.' })
  @MaxLength(50, {
    message: 'New password must be at most 50 characters long.',
  })
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message:
      'New password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.',
  })
  newPassword: string;
}
