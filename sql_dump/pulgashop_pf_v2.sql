-- MySQL dump 10.13  Distrib 8.0.42, for Win64 (x86_64)
--
-- Host: localhost    Database: pulgashop
-- ------------------------------------------------------
-- Server version	8.4.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `cuentas_oauth`
--

DROP TABLE IF EXISTS `cuentas_oauth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cuentas_oauth` (
  `id_cuenta` bigint unsigned NOT NULL AUTO_INCREMENT,
  `id_usuario` bigint unsigned NOT NULL,
  `proveedor` enum('google') NOT NULL,
  `id_proveedor` varchar(255) NOT NULL,
  `correo` varchar(255) DEFAULT NULL,
  `correo_verificado` tinyint(1) DEFAULT NULL,
  `nombre_completo` varchar(120) DEFAULT NULL,
  `avatar_url` varchar(500) DEFAULT NULL,
  `token_acceso` varbinary(1024) DEFAULT NULL,
  `token_refresco` varbinary(1024) DEFAULT NULL,
  `expira_en` datetime DEFAULT NULL,
  `ultimo_ingreso` datetime DEFAULT NULL,
  `creado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `actualizado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id_cuenta`),
  UNIQUE KEY `uq_oauth_proveedor_id` (`proveedor`,`id_proveedor`),
  KEY `idx_oauth_usuario` (`id_usuario`),
  CONSTRAINT `fk_oauth_usuario` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cuentas_oauth`
--

LOCK TABLES `cuentas_oauth` WRITE;
/*!40000 ALTER TABLE `cuentas_oauth` DISABLE KEYS */;
INSERT INTO `cuentas_oauth` VALUES (3,5,'google','google-uid-fran-001','fran@gmail.com',1,'Fran Meyer','https://images.example.com/avatars/fran_g.jpg',_binary ']>$ò&jòâª\ÎT\Z1',_binary '\Ì\Ô∞&ë\Èx9π´(ÜµO\‚\‡\÷X9\rBè=%ñL\√TV','2025-11-15 00:00:00','2025-09-15 10:30:00','2024-05-01 12:00:00','2025-09-15 10:30:00'),(4,6,'google','google-uid-lukas-001','lukas@gmail.com',1,'Lukas Scheel','https://images.example.com/avatars/lukas_g.jpg',_binary '^lànòs\ÌOsµU∑\≈v\„o\Ó\˜˙[¶\‘÷ùzm∞c',_binary 'ˇ¨°\«aéÄß´˚¥A”≠∫ŒÅ&!EpZvØΩó>\r','2025-10-30 00:00:00','2025-08-22 18:05:00','2024-06-10 09:00:00','2025-08-22 18:05:00'),(5,7,'google','google-uid-seba-001','sebastian@gmail.com',1,'Sebastian Rodriguez','https://images.example.com/avatars/seba_g.jpg',_binary 'çØk!k˙™7\“\ËW¯ç',_binary 'Z\Ë4∑Q\Ÿb˝G\÷DD⁄ÄiÆ;˝oç\ˆ•\ËHmÖ/\Ÿ','2025-09-15 00:00:00','2025-07-03 14:12:00','2024-07-20 16:40:00','2025-07-03 14:12:00');
/*!40000 ALTER TABLE `cuentas_oauth` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `perfiles`
--

DROP TABLE IF EXISTS `perfiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `perfiles` (
  `nombre_usuario` varchar(50) NOT NULL,
  `nombre_usuario_normalizado` varchar(50) GENERATED ALWAYS AS (lower(`nombre_usuario`)) STORED NOT NULL,
  `id_usuario` bigint unsigned NOT NULL,
  `nombre_completo` varchar(120) NOT NULL,
  `rut` varchar(12) NOT NULL,
  `foto` varchar(500) DEFAULT NULL,
  `biografia` varchar(280) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `pais` varchar(80) DEFAULT NULL,
  `ciudad` varchar(80) DEFAULT NULL,
  `direccion` varchar(200) DEFAULT NULL,
  `codigo_postal` varchar(20) DEFAULT NULL,
  `preferencias` json DEFAULT NULL,
  `creado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `actualizado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`nombre_usuario`),
  UNIQUE KEY `uq_perfiles_username_norm` (`nombre_usuario_normalizado`),
  UNIQUE KEY `uq_perfiles_id_usuario` (`id_usuario`),
  UNIQUE KEY `uq_perfiles_rut` (`rut`),
  UNIQUE KEY `uq_perfiles_telefono` (`telefono`),
  KEY `idx_perfiles_username_norm` (`nombre_usuario_normalizado`),
  CONSTRAINT `fk_perfiles_usuarios` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `perfiles`
--

LOCK TABLES `perfiles` WRITE;
/*!40000 ALTER TABLE `perfiles` DISABLE KEYS */;
INSERT INTO `perfiles` (`nombre_usuario`, `id_usuario`, `nombre_completo`, `rut`, `foto`, `biografia`, `telefono`, `pais`, `ciudad`, `direccion`, `codigo_postal`, `preferencias`, `creado_en`, `actualizado_en`) VALUES ('fran',5,'Fran Meyer','12345678-5','https://images.example.com/fran.jpg','QA & Backend en PulgaShop. Fan de los gatos y el caf√©.','+56998760001','Chile','Santiago','Los Alerces 1250, √ëu√±oa','7750000','{\"idioma\": \"es\", \"contacto\": \"email\", \"notificaciones\": true}','2024-05-01 12:00:00','2025-09-15 10:30:00'),('ignacio',8,'Ignacio Mendoza','87654321-4','https://images.example.com/ignacio.jpg','Moderaci√≥n y comunidad. Me gustan los libros.','+56998760004','Chile','La Serena','Av. del Mar 4500, Pe√±uelas','1700000','{\"idioma\": \"es\", \"contacto\": \"email\", \"notificaciones\": true}','2025-05-30 11:20:00','2025-06-01 08:00:00'),('lukas',6,'Lukas Scheel','11111111-1','https://images.example.com/lukas.jpg','Vendedor top en electr√≥nica. Amante del ciclismo.','+56998760002','Chile','Valpara√≠so','Av. Argentina 2401, Plan','2360000','{\"idioma\": \"es\", \"contacto\": \"whatsapp\", \"notificaciones\": true}','2024-06-10 09:00:00','2025-08-22 18:05:00'),('sebastian',7,'Sebastian Rodriguez','22222222-2','https://images.example.com/seba.jpg','Comprador frecuente, buscando ofertas reales.','+56998760003','Chile','Concepci√≥n','Barros Arana 920, Centro','4030000','{\"idioma\": \"es\", \"contacto\": \"email\", \"notificaciones\": false}','2024-07-20 16:40:00','2025-07-03 14:12:00');
/*!40000 ALTER TABLE `perfiles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permisos`
--

DROP TABLE IF EXISTS `permisos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permisos` (
  `id_permiso` bigint unsigned NOT NULL AUTO_INCREMENT,
  `codigo` varchar(100) NOT NULL,
  `descripcion` varchar(255) DEFAULT NULL,
  `creado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `actualizado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id_permiso`),
  UNIQUE KEY `uq_permisos_codigo` (`codigo`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permisos`
--

LOCK TABLES `permisos` WRITE;
/*!40000 ALTER TABLE `permisos` DISABLE KEYS */;
INSERT INTO `permisos` VALUES (16,'eliminar_usuario','Permite eliminar usuarios','2024-05-01 12:00:00','2024-05-01 12:00:00'),(17,'ver_reportes','Permite ver reportes del sistema','2024-05-01 12:00:00','2024-05-01 12:00:00'),(18,'editar_perfil','Permite modificar datos personales del perfil','2024-05-01 12:00:00','2024-05-01 12:00:00'),(19,'cambiar_foto_perfil','Permite subir o cambiar la imagen de perfil','2024-05-01 12:00:00','2024-05-01 12:00:00'),(20,'cambiar_contrase√±a','Permite actualizar la clave de acceso','2024-05-01 12:00:00','2024-05-01 12:00:00'),(21,'configurar_notificaciones','Permite activar o desactivar notificaciones','2024-05-01 12:00:00','2024-05-01 12:00:00'),(22,'ver_historial_ingresos','Permite ver el historial de sesiones iniciadas','2024-05-01 12:00:00','2024-05-01 12:00:00'),(23,'gestionar_privacidad','Permite configurar la visibilidad del perfil','2024-05-01 12:00:00','2024-05-01 12:00:00'),(24,'vincular_cuenta_oauth','Permite conectar cuentas externas como Google','2024-05-01 12:00:00','2024-05-01 12:00:00'),(25,'eliminar_cuenta','Permite solicitar la eliminaci√≥n de la cuenta','2024-05-01 12:00:00','2024-05-01 12:00:00'),(26,'ver_perfil_publico','Permite visualizar el perfil como lo ven otros usuarios','2024-05-01 12:00:00','2024-05-01 12:00:00'),(27,'gestionar_direcciones','Permite administrar direcciones personales','2024-05-01 12:00:00','2024-05-01 12:00:00'),(28,'modificar_contenido','Permite editar publicaciones, comentarios, etc.','2024-09-24 17:01:00','2024-09-24 17:01:00'),(29,'eliminar_contenido','Permite eliminar publicaciones, comentarios, etc.','2024-09-24 17:01:00','2024-09-24 17:01:00'),(30,'bloquear_usuario','Permite cambiar el estado de un usuario a \'bloqueado\'.','2024-09-24 17:01:00','2024-09-24 17:01:00');
/*!40000 ALTER TABLE `permisos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `roles`
--

DROP TABLE IF EXISTS `roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roles` (
  `id_rol` bigint unsigned NOT NULL AUTO_INCREMENT,
  `codigo` varchar(64) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `descripcion` varchar(255) DEFAULT NULL,
  `actualizado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id_rol`),
  UNIQUE KEY `uq_roles_codigo` (`codigo`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `roles`
--

LOCK TABLES `roles` WRITE;
/*!40000 ALTER TABLE `roles` DISABLE KEYS */;
INSERT INTO `roles` VALUES (5,'admin','Administrador','Acceso completo al sistema','2024-05-01 12:00:00'),(6,'vendedor','Vendedor','Puede publicar productos','2024-05-01 12:00:00'),(7,'cliente','Cliente','Puede comprar productos','2024-05-01 12:00:00'),(8,'moderador','Moderador','Puede modificar y eliminar publicaciones','2024-09-24 17:01:00');
/*!40000 ALTER TABLE `roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `roles_permisos`
--

DROP TABLE IF EXISTS `roles_permisos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roles_permisos` (
  `id_rol` bigint unsigned NOT NULL,
  `id_permiso` bigint unsigned NOT NULL,
  PRIMARY KEY (`id_rol`,`id_permiso`),
  KEY `fk_rp_permiso` (`id_permiso`),
  CONSTRAINT `fk_rp_permiso` FOREIGN KEY (`id_permiso`) REFERENCES `permisos` (`id_permiso`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_rp_rol` FOREIGN KEY (`id_rol`) REFERENCES `roles` (`id_rol`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `roles_permisos`
--

LOCK TABLES `roles_permisos` WRITE;
/*!40000 ALTER TABLE `roles_permisos` DISABLE KEYS */;
INSERT INTO `roles_permisos` VALUES (5,16),(5,17),(6,17),(7,17),(5,18),(6,18),(7,18),(6,19),(7,19),(6,20),(7,20),(6,21),(7,21),(5,22),(6,22),(6,23),(7,23),(6,24),(7,24),(6,25),(7,25),(6,26),(7,26),(6,27),(7,27),(8,28),(8,29),(5,30);
/*!40000 ALTER TABLE `roles_permisos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sesiones`
--

DROP TABLE IF EXISTS `sesiones`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sesiones` (
  `id_sesion` bigint unsigned NOT NULL AUTO_INCREMENT,
  `id_usuario` bigint unsigned NOT NULL,
  `token_refresco` char(64) NOT NULL,
  `agente_usuario` varchar(255) DEFAULT NULL,
  `direccion_ip` varbinary(16) DEFAULT NULL,
  `expira_en` datetime DEFAULT NULL,
  `creado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `revocado_en` datetime DEFAULT NULL,
  PRIMARY KEY (`id_sesion`),
  UNIQUE KEY `uq_sesiones_refresh` (`token_refresco`),
  KEY `idx_sesiones_usuario` (`id_usuario`),
  KEY `idx_sesiones_expira` (`expira_en`),
  CONSTRAINT `fk_sesiones_usuario` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sesiones`
--

LOCK TABLES `sesiones` WRITE;
/*!40000 ALTER TABLE `sesiones` DISABLE KEYS */;
INSERT INTO `sesiones` VALUES (4,5,'rf_fran_abcd1234_hash','Mozilla/5.0 (Windows NT 10.0)',_binary '¿®\0\n','2025-12-01 00:00:00','2025-09-15 10:30:00',NULL),(5,6,'rf_lukas_efgh5678_hash','Mozilla/5.0 (X11; Linux x86_64)',_binary '¿®\0','2025-10-30 00:00:00','2025-08-22 18:05:00',NULL),(6,7,'rf_seba_ijkl9012_hash','Mozilla/5.0 (Mac OS X)',_binary '¿®\0','2025-09-15 00:00:00','2025-07-03 14:12:00','2025-08-01 09:00:00');
/*!40000 ALTER TABLE `sesiones` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `usuarios`
--

DROP TABLE IF EXISTS `usuarios`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usuarios` (
  `id_usuario` bigint unsigned NOT NULL AUTO_INCREMENT,
  `correo` varchar(255) NOT NULL,
  `correo_normalizado` varchar(255) GENERATED ALWAYS AS (lower(`correo`)) STORED NOT NULL,
  `clave_hash` varchar(255) NOT NULL,
  `correo_verificado` tinyint(1) NOT NULL DEFAULT '0',
  `estado` enum('activo','bloqueado','pendiente') NOT NULL DEFAULT 'pendiente',
  `ultimo_ingreso` datetime DEFAULT NULL,
  `creado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `actualizado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `eliminado_en` datetime DEFAULT NULL,
  PRIMARY KEY (`id_usuario`),
  UNIQUE KEY `uq_usuarios_correo_norm` (`correo_normalizado`),
  KEY `idx_usuarios_estado` (`estado`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usuarios`
--

LOCK TABLES `usuarios` WRITE;
/*!40000 ALTER TABLE `usuarios` DISABLE KEYS */;
INSERT INTO `usuarios` (`id_usuario`, `correo`, `clave_hash`, `correo_verificado`, `estado`, `ultimo_ingreso`, `creado_en`, `actualizado_en`, `eliminado_en`) VALUES (5,'fran@pulgashop.cl','$2b$12$franhashxxxxxxxxxxxxxxxxxxxxxx111111111111111111111',1,'activo','2025-09-15 10:30:00','2024-05-01 12:00:00','2025-09-15 10:30:00',NULL),(6,'lukas@pulgashop.cl','$2b$12$lukashashxxxxxxxxxxxxxxxxxxxxx222222222222222222222',1,'activo','2025-08-22 18:05:00','2024-06-10 09:00:00','2025-08-22 18:05:00',NULL),(7,'sebastian@pulgashop.cl','$2b$12$sebahashxxxxxxxxxxxxxxxxxxxxxx333333333333333333333',1,'activo','2025-07-03 14:12:00','2024-07-20 16:40:00','2025-07-03 14:12:00',NULL),(8,'ignacio@pulgashop.cl','$2b$12$nachohashxxxxxxxxxxxxxxxxxxxxx444444444444444444444',0,'pendiente','2025-06-01 08:00:00','2025-05-30 11:20:00','2025-06-01 08:00:00',NULL);
/*!40000 ALTER TABLE `usuarios` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `usuarios_roles`
--

DROP TABLE IF EXISTS `usuarios_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usuarios_roles` (
  `id_usuario` bigint unsigned NOT NULL,
  `id_rol` bigint unsigned NOT NULL,
  `asignado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id_usuario`,`id_rol`),
  KEY `fk_ur_rol` (`id_rol`),
  CONSTRAINT `fk_ur_rol` FOREIGN KEY (`id_rol`) REFERENCES `roles` (`id_rol`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_ur_usuario` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usuarios_roles`
--

LOCK TABLES `usuarios_roles` WRITE;
/*!40000 ALTER TABLE `usuarios_roles` DISABLE KEYS */;
INSERT INTO `usuarios_roles` VALUES (5,5,'2024-05-01 12:00:00'),(6,6,'2024-06-10 09:00:00'),(7,7,'2024-07-20 16:40:00'),(8,8,'2025-05-30 11:20:00');
/*!40000 ALTER TABLE `usuarios_roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `verificaciones_correo`
--

DROP TABLE IF EXISTS `verificaciones_correo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `verificaciones_correo` (
  `id_verificacion` bigint unsigned NOT NULL AUTO_INCREMENT,
  `id_usuario` bigint unsigned NOT NULL,
  `token` char(64) NOT NULL,
  `expira_en` datetime DEFAULT NULL,
  `consumido_en` datetime DEFAULT NULL,
  `creado_en` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id_verificacion`),
  UNIQUE KEY `uq_verif_token` (`token`),
  KEY `idx_verif_usuario` (`id_usuario`),
  KEY `idx_verif_expira` (`expira_en`),
  CONSTRAINT `fk_verif_usuario` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `verificaciones_correo`
--

LOCK TABLES `verificaciones_correo` WRITE;
/*!40000 ALTER TABLE `verificaciones_correo` DISABLE KEYS */;
INSERT INTO `verificaciones_correo` VALUES (3,5,'verif_fran_2024_abc_hash','2024-06-01 23:59:59','2024-05-01 12:05:00','2024-05-01 12:00:00'),(4,6,'verif_lukas_2024_def_hash','2024-07-10 23:59:59','2024-06-10 09:02:00','2024-06-10 09:00:00'),(5,7,'verif_seba_2024_ghi_hash','2024-08-20 23:59:59','2024-07-20 16:42:00','2024-07-20 16:40:00'),(6,8,'verif_ignacio_2025_abc_hash','2025-06-15 23:59:59',NULL,'2025-05-30 11:20:00');
/*!40000 ALTER TABLE `verificaciones_correo` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-10-12 20:09:02
