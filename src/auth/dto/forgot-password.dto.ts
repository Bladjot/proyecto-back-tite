import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ForgotPasswordDto {
  @ApiProperty({
    example: 'usuario@pulgashop.cl',
    description: 'Correo asociado a la cuenta',
  })
  @IsEmail()
  @IsNotEmpty()
  correo: string;
}
