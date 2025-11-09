import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreateVendorAccreditationDto {
  @ApiProperty({ description: 'Nombre de la tienda', example: 'PulgaShop Store' })
  @IsString()
  @IsNotEmpty()
  storeName: string;

  @ApiProperty({ description: 'Número de contacto', example: '+56987654321' })
  @IsString()
  @IsNotEmpty()
  contactNumber: string;

  @ApiProperty({ description: 'RUT de la empresa', example: '76.123.456-7' })
  @IsString()
  @IsNotEmpty()
  companyRut: string;
}
