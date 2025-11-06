import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsObject, IsOptional, IsString } from 'class-validator';

export class UpdateProfileDetailsDto {
  @ApiPropertyOptional({ description: 'Biografía del usuario' })
  @IsOptional()
  @IsString()
  biografia?: string;

  @ApiPropertyOptional({ description: 'Preferencias del usuario', type: Object })
  @IsOptional()
  @IsObject()
  preferencias?: Record<string, any>;
}

