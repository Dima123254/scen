# Входные данные организации

Скопируйте `company_data.template.json` в `company_data.json` (или укажите свой путь в CLI) и заполните поля.

## Поля

- **meta** — `company_name` (обязательно), `system_name`, `author`, `date`.
- **assets** — активы: `id`, `name`, `zone` (`Internal`, `External`, `DMZ`, `Filial`), `interfaces`, `data_types`, `description`.
- **topology** — связи: `from`, `to` (идентификаторы активов), `protocol`.
- **attackers** — нарушители: `type`, `level` (`Н1`–`Н4`), `category` (`External`, `Internal`, `External/Internal`), `goals`, опционально `interfaces`.
- **threats** — список кодов УБИ (`УБИ.1` … `УБИ.11`).
- **business_processes** — процессы: `name`, `threats`, `consequences`.

Поля с префиксом `_help` или `_readme` в шаблоне можно удалить после заполнения; парсер их игнорирует.

## Топология и фильтр DMZ

Для внешнего нарушителя и актива в зоне `Internal` в графе топологии должен существовать путь через актив с зоной `DMZ`; прямое соединение `External` → `Internal` без DMZ даёт отклонение сценария фильтром `topology`.

## Интерфейсы

Если у нарушителя не задан список `interfaces`, используются значения по умолчанию из `config/validation_config.yaml` (`default_external_interfaces` / `default_internal_interfaces`). Для прохождения фильтра `interface` должно быть пересечение с интерфейсами целевого актива.
