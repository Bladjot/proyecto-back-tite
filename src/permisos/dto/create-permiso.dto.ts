import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreatePermisoDto {
  @ApiProperty({ example: 'crear_producto', description: 'Código único del permiso' })
  @IsNotEmpty()
  @IsString()
  codigo: string;

  @ApiProperty({ example: 'Crear Producto', description: 'Nombre visible del permiso' })
  @IsNotEmpty()
  @IsString()
  nombre: string;

  @ApiProperty({ example: 'Permite a un usuario crear productos', description: 'Descripción del permiso' })
  @IsString()
  descripcion?: string;
}
