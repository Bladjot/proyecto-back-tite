import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { RolesModule } from './roles/roles.module';
import { PermisosModule } from './permisos/permisos.module';
import { RolesPermisosModule } from './roles-permisos/roles-permisos.module';
import { VerificacionesCorreoModule } from './verificaciones-correo/verificaciones-correo.module'; // 👈 nuevo
import { VendorAccreditationsModule } from './vendor-accreditations/vendor-accreditations.module';

@Module({
  imports: [
    // Carga y valida las variables de entorno
    ConfigModule.forRoot({
      isGlobal: true, // Disponible en toda la aplicación
    }),

    // Conexión a MongoDB
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('MONGODB_URI'),
      }),
    }),

    // Módulos de la aplicación
    AuthModule,
    UsersModule,
    RolesModule,
    PermisosModule,
    RolesPermisosModule,
    VerificacionesCorreoModule, // 👈 nuevo
    VendorAccreditationsModule,
  ],
})
export class AppModule {}
