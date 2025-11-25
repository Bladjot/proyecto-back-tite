// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { join } from 'path';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // ⚙️ Habilitar CORS (para conexión con el frontend)
  app.enableCors({
    origin: ['http://localhost:5173', 'http://localhost:5174', 'http://localhost'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
  });

  // ⚙️ Validación global de DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
  );

  // Prefijo global para todos los endpoints
  app.setGlobalPrefix('api');

  // 📂 Archivos estáticos (fotos de perfil)
  app.useStaticAssets(join(__dirname, '..', 'uploads'), {
    prefix: '/uploads/',
  });

  // 📘 Configuración de Swagger actualizada
  const config = new DocumentBuilder()
    .setTitle('API GPI - Sistema de Roles y Usuarios')
    .setDescription(`
      Documentación de la API GPI con sistema de autenticación, roles y permisos.
      
      ### Roles disponibles:
      - 👑 **admin:** puede crear, modificar, eliminar y ver todos los usuarios.
      - 🧑‍💼 **moderador:** puede modificar y eliminar usuarios normales, pero **no** puede eliminar administradores.
      - 👤 **cliente:** rol básico; puede ver y editar su propio perfil y se convierte en vendedor una vez verificado.

      ### Endpoints principales:
      - **/api/auth/** → registro, login, autenticación Google.
      - **/api/users/** → CRUD de usuarios.
      - **/api/roles/** → gestión de roles.
      - **/api/permisos/** → gestión de permisos.
      ### Endpoints para los demas grupos:
      - ** /api/users/public/:id (grupo 10-9-2)
      - ** /auth/me (Grupo 6)
      - ** /auth/can-access (Grupo 1)
      ### Notas para los demas grupos:
      GET /api/auth/me: requiere JWT. Usa header Authorization: Bearer <token>; devuelve id, nombre, apellido, correo, roles, permisos del usuario autenticado.
      GET /api/auth/can-access: requiere el mismo header y un query page=<codigo_permiso>. Responde { page, hasAccess } para confirmar si el permiso está en la lista del usuario.
      GET /api/users/public/:id: público; solo sustituyes :id por el ObjectId del usuario. Entrega un perfil básico (id, nombre, apellido, correo, activo, timestamps) sin datos sensibles.
    `)
    .setVersion('1.0')
    .addBearerAuth() // Permite enviar el token JWT desde Swagger
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document);

  const port = process.env.PORT || 3000;
  await app.listen(port);

  console.log(`✅ Servidor ejecutándose en: http://localhost:${port}/api`);
  console.log(`📘 Swagger disponible en: http://localhost:${port}/api-docs`);
}
bootstrap();
