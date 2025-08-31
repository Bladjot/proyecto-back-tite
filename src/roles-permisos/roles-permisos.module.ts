import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RolesPermisosService } from './roles-permisos.service';
import { RolesPermisosController } from './roles-permisos.controller';
import { RolePermiso, RolePermisoSchema } from './schemas/role-permiso.schema';

@Module({
  imports: [MongooseModule.forFeature([{ name: RolePermiso.name, schema: RolePermisoSchema }])],
  controllers: [RolesPermisosController],
  providers: [RolesPermisosService],
  exports: [RolesPermisosService],
})
export class RolesPermisosModule {}
