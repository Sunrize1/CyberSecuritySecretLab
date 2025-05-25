# Инструкция по развертыванию CTF-задачи "Секретная Лаборатория"

## Быстрое развертывание

### 1. Клонирование и запуск

```bash
# Клонируйте репозиторий
git clone <repository-url>
cd cyberSecurity

# Запустите сервисы
docker-compose up -d

# Проверьте статус
docker-compose ps
```

### 2. Проверка работоспособности

```bash
# Проверьте доступность веб-интерфейса
curl http://localhost:8080

# Проверьте базу данных
docker-compose exec db mysql -u lab_user -plab_password_456 -e "SHOW DATABASES;"
```

### 3. Доступ к сервису

- **URL:** http://localhost:8080
- **Порт веб-сервиса:** 8080
- **Порт базы данных:** 3306 (для отладки)
