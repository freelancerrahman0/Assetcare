-- AssetCare MySQL Schema & Seed
-- Default local database: assetcare_db
-- Live Server Note: If your live host uses a different database name (e.g. cpaneluser_assetcare),
-- select that database first in phpMyAdmin and delete or update the next two lines before importing.
-- Built by Abdur Rahman

CREATE DATABASE IF NOT EXISTS `assetcare_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `assetcare_db`;

SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';
SET FOREIGN_KEY_CHECKS = 0;
SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS `users` (
  `username` VARCHAR(100) NOT NULL,
  `email` VARCHAR(191) NOT NULL DEFAULT '',
  `passwordHash` VARCHAR(255) NOT NULL DEFAULT '',
  `role` ENUM('admin','Maintenance','IT Support','Management') NOT NULL DEFAULT 'Maintenance',
  `status` ENUM('active','blocked','pending') NOT NULL DEFAULT 'active',
  `requestDate` VARCHAR(100) NOT NULL DEFAULT '',
  `lastSeen` BIGINT NOT NULL DEFAULT 0,
  `mustResetPassword` TINYINT(1) NOT NULL DEFAULT 1,
  `reset_code` VARCHAR(255) NULL DEFAULT NULL,
  `reset_expires` VARCHAR(64) NULL DEFAULT NULL,
  `api_token` VARCHAR(128) NULL DEFAULT NULL,
  `token_expires_at` BIGINT NULL DEFAULT NULL,
  PRIMARY KEY (`username`),
  INDEX `idx_users_token` (`api_token`),
  INDEX `idx_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `assets` (
  `tag` VARCHAR(100) NOT NULL,
  `type` VARCHAR(100) NOT NULL DEFAULT 'Laptop',
  `brand` VARCHAR(100) NOT NULL DEFAULT '',
  `model` VARCHAR(150) NOT NULL DEFAULT '',
  `serial` VARCHAR(150) NOT NULL DEFAULT '',
  `status` VARCHAR(80) NOT NULL DEFAULT 'N/A',
  `purchaseDate` VARCHAR(64) NOT NULL DEFAULT '',
  `repairCount` INT NOT NULL DEFAULT 0,
  `deliveryCount` INT NOT NULL DEFAULT 0,
  `repairs_json` LONGTEXT NULL,
  `warranty_stage` VARCHAR(150) NULL DEFAULT NULL,
  `warranty_issue` TEXT NULL DEFAULT NULL,
  `warranty_vendor` VARCHAR(150) NULL DEFAULT NULL,
  `warranty_received_date` VARCHAR(64) NULL DEFAULT NULL,
  PRIMARY KEY (`tag`),
  INDEX `idx_assets_serial` (`serial`),
  INDEX `idx_assets_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `slots` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `sn` VARCHAR(50) NOT NULL DEFAULT '',
  `date_val` VARCHAR(64) NOT NULL DEFAULT '',
  `slotNo` VARCHAR(100) NOT NULL DEFAULT '',
  `slotName` VARCHAR(150) NOT NULL DEFAULT 'Laptop Repair',
  `totalAssets` INT NOT NULL DEFAULT 0,
  `returnToIT` INT NOT NULL DEFAULT 0,
  `eol` INT NOT NULL DEFAULT 0,
  `pending` INT NOT NULL DEFAULT 0,
  `remarks` TEXT NULL,
  `slotAssets_json` LONGTEXT NULL,
  `slotAccessories_json` LONGTEXT NULL,
  `receivedByMaintenance` TINYINT(1) NOT NULL DEFAULT 0,
  `receivedAt` VARCHAR(64) NULL DEFAULT NULL,
  `receivedBy` VARCHAR(100) NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `vendors` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `vendorName` VARCHAR(150) NOT NULL DEFAULT '',
  `companyName` VARCHAR(191) NOT NULL DEFAULT '',
  `phone` VARCHAR(64) NOT NULL DEFAULT '',
  `email` VARCHAR(191) NOT NULL DEFAULT '',
  `createdAt` VARCHAR(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `assessment_products` (
  `productName` VARCHAR(191) NOT NULL,
  PRIMARY KEY (`productName`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `system_meta` (
  `meta_key` VARCHAR(100) NOT NULL,
  `meta_value` TEXT NULL,
  PRIMARY KEY (`meta_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `auth_rate_limits` (
  `rate_key` VARCHAR(191) NOT NULL,
  `attempts` INT NOT NULL DEFAULT 0,
  `last_attempt` BIGINT NOT NULL DEFAULT 0,
  `blocked_until` BIGINT NULL DEFAULT NULL,
  PRIMARY KEY (`rate_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `password_reset_sessions` (
  `token` VARCHAR(128) NOT NULL,
  `username` VARCHAR(100) NOT NULL,
  `expires_at` BIGINT NOT NULL,
  PRIMARY KEY (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO `system_meta` (`meta_key`, `meta_value`) VALUES ('data_version', '1');
SET FOREIGN_KEY_CHECKS = 1;
