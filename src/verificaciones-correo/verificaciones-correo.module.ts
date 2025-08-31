import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { VerificacionesCorreoService } from './verificaciones-correo.service';
import { VerificacionesCorreoController } from './verificaciones-correo.controller';
import { VerificacionCorreo, VerificacionCorreoSchema } from './schemas/verificacion-correo.schema';

@Module({
  imports: [MongooseModule.forFeature([{ name: VerificacionCorreo.name, schema: VerificacionCorreoSchema }])],
  controllers: [VerificacionesCorreoController],
  providers: [VerificacionesCorreoService],
  exports: [VerificacionesCorreoService],
})
export class VerificacionesCorreoModule {}
