import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { PermisosService } from './permisos.service';
import { PermisosController } from './permisos.controller';
import { Permiso, PermisoSchema } from './schemas/permiso.schema';

@Module({
  imports: [MongooseModule.forFeature([{ name: Permiso.name, schema: PermisoSchema }])],
  controllers: [PermisosController],
  providers: [PermisosService],
  exports: [PermisosService],
})
export class PermisosModule {}
