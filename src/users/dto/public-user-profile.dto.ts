export class PublicUserProfileDto {
  id: string;
  nombre: string;
  apellido: string;
  correo: string;
  rut: string;
  activo: boolean;
  creado_en?: Date;
  actualizado_en?: Date;
}
