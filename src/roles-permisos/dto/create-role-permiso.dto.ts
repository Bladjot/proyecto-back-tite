import { IsNotEmpty, IsString } from 'class-validator';

export class CreateRolePermisoDto {
  @IsNotEmpty()
  @IsString()
  roleId: string;

  @IsNotEmpty()
  @IsString()
  permisoId: string;
}
