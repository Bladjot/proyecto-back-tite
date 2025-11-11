// ✅ src/users/users.service.ts
import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PublicUserProfileDto } from './dto/public-user-profile.dto';
import { Role, RoleDocument } from '../roles/schemas/role.schema';
import {
  RolePermiso,
  RolePermisoDocument,
} from '../roles-permisos/schemas/role-permiso.schema';
import { Permiso, PermisoDocument } from '../permisos/schemas/permiso.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(Role.name) private readonly roleModel: Model<RoleDocument>,
    @InjectModel(RolePermiso.name)
    private readonly rolePermisoModel: Model<RolePermisoDocument>,
    @InjectModel(Permiso.name)
    private readonly permisoModel: Model<PermisoDocument>,
  ) {}

  /**
   * 🧩 Crear un nuevo usuario
   */
  async create(createUserDto: CreateUserDto): Promise<User> {
    const rolesNormalizados =
      (createUserDto.roles && createUserDto.roles.length > 0
        ? createUserDto.roles
        : ['cliente']);

    const permisosPorRol = await this.obtenerPermisosDesdeRoles(
      rolesNormalizados,
    );
    const permisosExtras = Array.isArray(createUserDto.permisos)
      ? createUserDto.permisos
      : [];
    const permisosUnicos = this.unificarPermisos([
      ...permisosPorRol,
      ...permisosExtras,
    ]);

    const payload = {
      ...createUserDto,
      roles: rolesNormalizados,
      permisos: permisosUnicos,
    };

    const newUser = new this.userModel(payload);
    return await newUser.save();
  }

  /**
   * 🔍 Buscar todos los usuarios
   */
  async findAll(): Promise<any[]> {
    const users = await this.userModel
      .find()
      .select(
        'nombre apellido correo telefono rut roles permisos activo foto creado_en actualizado_en',
      )
      .lean()
      .exec();

    return users.map((doc) => {
      const user = doc as any;
      return {
        id: user._id?.toString?.() ?? user.id,
        nombre: user.nombre,
        apellido: user.apellido,
        correo: user.correo,
        telefono: user.telefono ?? null,
        rut: user.rut,
        roles: user.roles ?? [],
        permisos: user.permisos ?? [],
        activo: user.activo,
        foto: user.foto ?? null,
        creado_en: user.creado_en,
        actualizado_en: user.actualizado_en,
      };
    });
  }

  /**
   * 🔍 Buscar usuario por ID
   */
  async findOne(id: string): Promise<any> {
    const user = await this.userModel
      .findById(id)
      .select(
        'nombre apellido correo telefono rut roles permisos activo foto creado_en actualizado_en',
      )
      .lean()
      .exec();
    if (!user) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }
    const normalized = user as any;
    return {
      id: normalized._id?.toString?.() ?? normalized.id,
      nombre: normalized.nombre,
      apellido: normalized.apellido,
      correo: normalized.correo,
      telefono: normalized.telefono ?? null,
      rut: normalized.rut,
      roles: normalized.roles ?? [],
      permisos: normalized.permisos ?? [],
      activo: normalized.activo,
      foto: normalized.foto ?? null,
      creado_en: normalized.creado_en,
      actualizado_en: normalized.actualizado_en,
    };
  }

  /**
   * Perfil extendido: devuelve solo la biografía del usuario
   */
  async findProfileDetails(id: string): Promise<{
    biografia: string | null;
    preferencias: any | null;
    correo: string;
    telefono: string | null;
  }> {
    const user = await this.userModel
      .findById(id)
      .select('biografia preferencias correo telefono')
      .lean()
      .exec();

    if (!user) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    const { biografia = null, preferencias = null, correo, telefono = null } = (user as any) || {};
    return { biografia, preferencias, correo, telefono };
  }

  /**
   * Actualizar nombre, apellido y/o biografía del usuario autenticado
   */
  async updateProfileDetails(
    id: string,
    payload: {
      nombre?: string;
      apellido?: string;
      biografia?: string;
      foto?: string | null;
      preferencias?: Record<string, any> | null;
      telefono?: string | null;
      correo?: string;
      contrasenaHash?: string;
    },
  ): Promise<{
    biografia: string | null;
    foto: string | null;
    preferencias: any | null;
    correo: string;
    telefono: string | null;
  }> {
    const $set: any = {};
    if (typeof payload.nombre !== 'undefined') $set.nombre = payload.nombre;
    if (typeof payload.apellido !== 'undefined') $set.apellido = payload.apellido;
    if (typeof payload.biografia !== 'undefined') $set.biografia = payload.biografia;
    if (typeof payload.foto !== 'undefined') $set.foto = payload.foto;
    if (typeof payload.preferencias !== 'undefined') $set.preferencias = payload.preferencias;
    if (typeof payload.telefono !== 'undefined') $set.telefono = payload.telefono;
    if (typeof payload.correo !== 'undefined') $set.correo = payload.correo;
    if (typeof payload.contrasenaHash !== 'undefined') $set.contrasena = payload.contrasenaHash;

    const updated = await this.userModel
      .findByIdAndUpdate(id, { $set }, { new: true })
      .select('biografia foto preferencias correo telefono')
      .lean()
      .exec();

    if (!updated) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    return {
      biografia: (updated as any)?.biografia ?? null,
      foto: (updated as any)?.foto ?? null,
      preferencias: (updated as any)?.preferencias ?? null,
      correo: (updated as any)?.correo,
      telefono: (updated as any)?.telefono ?? null,
    };
  }

  /**
   * Obtener usuario con contraseña (uso interno)
   */
  async findByIdWithPassword(id: string): Promise<User | null> {
    return this.userModel.findById(id).exec();
  }

  /**
   * 👤 Perfil público sin datos sensibles
   */
  async findPublicProfile(id: string): Promise<PublicUserProfileDto> {
    const user = await this.userModel
      .findById(id)
      .select('nombre apellido correo rut activo creado_en actualizado_en')
      .lean()
      .exec();

    if (!user) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    const { _id, nombre, apellido, correo, rut, activo, creado_en, actualizado_en } = user as any;

    return {
      id: _id?.toString?.() ?? String(_id),
      nombre,
      apellido,
      correo,
      rut,
      activo,
      creado_en,
      actualizado_en,
    } as PublicUserProfileDto;
  }

  /**
   * 🔍 Buscar usuario por correo (usado por AuthService)
   */
  async findByCorreo(correo: string): Promise<User | null> {
    return await this.userModel.findOne({ correo }).exec();
  }

  /**
   * ✏️ Actualizar un usuario
   */
  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const updatedUser = await this.userModel
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .exec();

    if (!updatedUser) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    return updatedUser;
  }

  /**
   * 🗑️ Eliminar usuario (Admin y Moderador)
   * - Admin puede eliminar cualquier usuario.
   * - Moderador puede eliminar usuarios normales o moderadores,
   *   pero NO puede eliminar a un administrador.
   */
  async remove(id: string, currentUser?: any): Promise<{ message: string }> {
    const userToDelete = await this.userModel.findById(id).exec();
    if (!userToDelete) {
      throw new NotFoundException(`Usuario con ID ${id} no encontrado`);
    }

    const currentRoles = currentUser?.roles || [];
    const targetRoles = userToDelete.roles || [];

    if (currentRoles.includes('moderador') && targetRoles.includes('admin')) {
      throw new ForbiddenException(
        'Un moderador no puede eliminar a un administrador',
      );
    }

    await this.userModel.findByIdAndDelete(id).exec();
    return { message: 'Usuario eliminado correctamente' };
  }

  /**
   * Calcula los permisos asociados a un conjunto de roles
   */
  private async obtenerPermisosDesdeRoles(roles: string[]): Promise<string[]> {
    if (!Array.isArray(roles) || roles.length === 0) {
      return [];
    }

    const normalizados = roles
      .map((rol) => rol?.trim())
      .filter((rol): rol is string => Boolean(rol))
      .map((rol) => rol.toLowerCase());

    if (normalizados.length === 0) {
      return [];
    }

    const rolesDocs = await this.roleModel
      .find({ codigo: { $in: normalizados } })
      .select('_id codigo')
      .lean();

    if (rolesDocs.length === 0) {
      return [];
    }

    const roleIds = rolesDocs.map((rol) => rol._id);

    const relacionesModernas = await this.rolePermisoModel
      .find({ roleId: { $in: roleIds } })
      .select('permisoId')
      .lean();

    const permisoIds = relacionesModernas
      .map((rel) => rel.permisoId as Types.ObjectId | undefined)
      .filter((id): id is Types.ObjectId => Boolean(id));

    if (permisoIds.length > 0) {
      const permisosDocs = await this.permisoModel
        .find({ _id: { $in: permisoIds } })
        .select('codigo')
        .lean();

      return this.unificarPermisos(
        permisosDocs
          .map((permiso) => permiso.codigo)
          .filter((codigo): codigo is string => Boolean(codigo)),
      );
    }

    // Compatibilidad con estructura anterior (rol_codigo + permisos[])
    const legacyRelations = await this.rolePermisoModel.collection
      .find({ rol_codigo: { $in: normalizados } })
      .project({ rol_codigo: 1, permisos: 1 })
      .toArray();

    if (legacyRelations.length === 0) {
      return [];
    }

    return this.unificarPermisos(
      legacyRelations.flatMap((rel) =>
        Array.isArray(rel.permisos) ? rel.permisos : [],
      ),
    );
  }

  private unificarPermisos(permisos: string[]): string[] {
    return Array.from(
      new Set(
        permisos
          .map((permiso) => permiso?.trim())
          .filter((permiso): permiso is string => Boolean(permiso)),
      ),
    );
  }
}
