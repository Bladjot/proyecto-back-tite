// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // ⚙️ Habilitar CORS (para conexión con el frontend)
  app.enableCors({
    origin: 'http://localhost:5173',
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

  // 📘 Configuración de Swagger actualizada
  const config = new DocumentBuilder()
    .setTitle('API GPI - Sistema de Roles y Usuarios')
    .setDescription(`
      Documentación de la API GPI con sistema de autenticación, roles y permisos.
      
      ### Roles disponibles:
      - 👑 **admin:** puede crear, modificar, eliminar y ver todos los usuarios.
      - 🧑‍💼 **moderador:** puede modificar y eliminar usuarios normales, pero **no** puede eliminar administradores.
      - 👤 **usuario:** rol básico; puede ver y editar su propio perfil.

      ### Endpoints principales:
      - **/api/auth/** → registro, login, autenticación Google.
      - **/api/users/** → CRUD de usuarios.
      - **/api/roles/** → gestión de roles.
      - **/api/permisos/** → gestión de permisos.
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
