import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { User, UserSchema } from './schemas/user.schema';
import { Role, RoleSchema } from '../roles/schemas/role.schema';
import { Permiso, PermisoSchema } from '../permisos/schemas/permiso.schema';
import {
  RolePermiso,
  RolePermisoSchema,
} from '../roles-permisos/schemas/role-permiso.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: RoleSchema },
      { name: Permiso.name, schema: PermisoSchema },
      { name: RolePermiso.name, schema: RolePermisoSchema },
    ]),
  ],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService], // Exportamos el servicio para que pueda ser usado por otros módulos
})
export class UsersModule {}
