import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreateVendorAccreditationDto {
  @ApiProperty({ description: 'Nombre de la tienda', example: 'PulgaShop Store' })
  @IsString()
  @IsNotEmpty()
  nombre_tienda: string;

  @ApiProperty({ description: 'Número de contacto', example: '+56987654321' })
  @IsString()
  @IsNotEmpty()
  telefono_contacto: string;

  @ApiProperty({ description: 'RUT de la empresa', example: '76.123.456-7' })
  @IsString()
  @IsNotEmpty()
  rut_empresa: string;
}
