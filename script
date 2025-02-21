# Импортируем модуль Active Directory
Import-Module ActiveDirectory

# Функция для отображения списка OU с описанием
function Show-OUs {
    param (
        [array]$OUs,
        [string]$ParentOU = "",
        [int]$Level = 0
    )

    $ouList = @()

    # Фильтрация OU на текущем уровне
    foreach ($ou in $OUs) {
        $ouName = ($ou -split ',')[0] -replace 'OU=', ''
        $ouPath = $ou -replace '^OU=([^,]+),', ''
        $currentLevel = ($ouPath -split 'OU=').Count - 1

        # Выводим OU, если его уровень совпадает с текущим и он является дочерним для ParentOU
        if ($currentLevel -eq $Level -and ($ParentOU -eq "" -or $ouPath -eq $ParentOU)) {
            $ouDescription = (Get-ADOrganizationalUnit -Identity $ou -Properties Description).Description
            $ouList += [PSCustomObject]@{
                Name        = $ouName
                Path        = $ou
                Level       = $currentLevel
                Description = $ouDescription
            }
        }
    }

    # Сортируем OU по имени
    $ouList = $ouList | Sort-Object -Property Name

    # Выводим OU в виде списка
    $counter = 1
    foreach ($ou in $ouList) {
        $description = if ([string]::IsNullOrEmpty($ou.Description)) { "Нет описания" } else { $ou.Description }
        Write-Host "$counter. $($ou.Name) - $description"
        $counter++
    }

    return $ouList
}

# Функция для выбора подразделения (OU)
function Select-OU {
    param (
        [string]$ParentOU = "",
        [int]$Level = 0
    )

    # Получаем все OU
    $OUs = Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
    Write-Host "Выберите подразделение (OU):"
    
    # Показать только родительские OU на текущем уровне
    $ouList = Show-OUs -OUs $OUs -ParentOU $ParentOU -Level $Level

    # Если список пуст, возвращаем $selectedOU
    if ($ouList.Count -eq 0) {
        Write-Host "Нет доступных подразделений."
        return $selectedOU
    }

    # Добавляем возможность подняться на уровень вверх, если мы не на верхнем уровне
    if ($Level -gt 0) {
        Write-Host "$($ouList.Count + 1). Подняться на уровень вверх"
    }

    $choice = Read-Host "Введите номер подразделения (или '0' для выхода)"
    
    if ($choice -eq 0) {
        return $null
    }

    # Если выбрали "подняться вверх"
    if ($choice -eq ($ouList.Count + 1) -and $Level -gt 0) {
        # Убираем текущий OU из пути
        $parentPath = $ParentOU -replace '^OU=[^,]+,', ''
        return Select-OU -ParentOU $parentPath -Level ($Level - 1)
    }

    # Получаем выбранное подразделение
    $selectedOU = $ouList[$choice - 1].Path

    # Получаем только дочерние подразделения для выбранного родительского OU
    $childOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $selectedOU | Select-Object -ExpandProperty DistinguishedName

    # Если есть дочерние OU, даем возможность выбрать вложенные OU
    if ($childOUs.Count -gt 0) {
        Write-Host "Выбранное подразделение: $($ouList[$choice - 1].Name)"
        Write-Host "Есть вложенные подразделения. Хотите выбрать одно из них?"
        $confirm = Read-Host "Введите 'да' для выбора вложенного подразделения или 'нет' для использования текущего"
        if ($confirm -eq 'да') {
            return Select-OU -ParentOU $selectedOU -Level ($Level + 1)
        }
    }

    return $selectedOU
}

# Функция для генерации логина
function Generate-Username {
    param (
        [string]$FirstName,
        [string]$LastName,
        [string]$MiddleName
    )

    # Обработка фамилии
    $lastNameFirstTranslit = Get-FirstLetterTranslit -Name $LastName
    $lastNameRest = if ($LastName.Length -gt 1) { $LastName.Substring(1) } else { "" }
    $lastNameRestTranslit = Transliterate-Name -Name $lastNameRest
    $lastNamePart = $lastNameFirstTranslit.ToUpper() + $lastNameRestTranslit.ToLower()

    # Обработка имени
    $firstNameFirstTranslit = Get-FirstLetterTranslit -Name $FirstName
    $firstNamePart = $firstNameFirstTranslit.ToUpper()

    # Обработка отчества
    $middleNameFirstTranslit = Get-FirstLetterTranslit -Name $MiddleName
    $middleNamePart = $middleNameFirstTranslit.ToUpper()

    # Сборка логина
    $login = $lastNamePart + $firstNamePart + $middleNamePart

    return $login
}

# Функция для поиска пользователя в четыр форматах
function Find-User {
    param (
        [string]$LastName,
        [string]$FirstName,
        [string]$MiddleName,
        [string]$OU
    )
    # Формат 1: Логин (IvanovII)
    $login = Generate-Username -FirstName $FirstName -LastName $LastName -MiddleName $MiddleName
    $user = Get-ADUser -Filter "SamAccountName -eq '$login'" -SearchBase $OU -ErrorAction SilentlyContinue
    if ($user) {
        return $user
    }

    # Формат 2: Полное ФИО на кириллице
    $user = Get-ADUser -Filter {
        GivenName -eq $FirstName -and
        Surname -eq $LastName -and
        MiddleName -eq $MiddleName
    } -SearchBase $OU -ErrorAction SilentlyContinue
    if ($user) {
        return $user
    }

    # Формат 3: ФИО в нижнем регистре на латинице

    $translitFirstName = Transliterate-Name -Name $FirstName
    $translitLastName = Transliterate-Name -Name $LastName
    $translitMiddleName = Transliterate-Name -Name $MiddleName

    # Формируем строки для фильтра
    $formattedLastName = $translitLastName.Substring(0,1).ToUpper() + $translitLastName.Substring(1).ToLower()
    $formattedFirstName = $translitFirstName.Substring(0,1).ToUpper() + $translitFirstName.Substring(1).ToLower()
    $formattedMiddleName = $translitMiddleName.Substring(0,1).ToUpper() + $translitMiddleName.Substring(1).ToLower()
    $formattedDisplayName = "$formattedLastName $formattedFirstName $formattedMiddleName"

    $user = Get-ADUser -Filter {
       
        DisplayName -eq $formattedDisplayName 
        
    } -SearchBase $OU -ErrorAction SilentlyContinue

    if ($user) {
        return $user
    }
        # Формат 4: ФИО в верхнем регистре на латинице
    $translitLastName = Transliterate-Name -Name $LastName
    $translitFirstName = Transliterate-Name -Name $FirstName
    $translitMiddleName = Transliterate-Name -Name $MiddleName
    $translitDisplayName = "$translitLastName.ToUpper() $translitFirstName.ToUpper() $translitMiddleName.ToUpper()"

    $user = Get-ADUser -Filter { DisplayName -eq $translitDisplayName } -SearchBase $OU -ErrorAction SilentlyContinue
    if ($user) {
        return $user
    }

    return $null
}

# Функция для транслитерации ФИО
function Transliterate-Name {
    param (
        [string]$Name
    )
    $translitMap = @{
        'а' = 'a'; 'б' = 'b'; 'в' = 'v'; 'г' = 'g'; 'д' = 'd'; 'е' = 'e'; 'ё' = 'e';
        'ж' = 'zh'; 'з' = 'z'; 'и' = 'i'; 'й' = 'i'; 'к' = 'k'; 'л' = 'l'; 'м' = 'm';
        'н' = 'n'; 'о' = 'o'; 'п' = 'p'; 'р' = 'r'; 'с' = 's'; 'т' = 't'; 'у' = 'u';
        'ф' = 'f'; 'х' = 'kh'; 'ц' = 'ts'; 'ч' = 'ch'; 'ш' = 'sh'; 'щ' = 'shch';
        'ы' = 'y'; 'ъ' = 'ie'; 'э' = 'e'; 'ю' = 'iu'; 'я' = 'ia'
    }

    $transliteratedName = ""
    foreach ($char in $Name.ToCharArray()) {
        $lowerChar = $char.ToString().ToLower()
        if ($translitMap.ContainsKey($lowerChar)) {
            $transliteratedName += $translitMap[$lowerChar]
        } else {
            $transliteratedName += $char
        }
    }
    return $transliteratedName
}

# Функция для получения транслитерации первой буквы
function Get-FirstLetterTranslit {
    param (
        [string]$Name
    )
    if ([string]::IsNullOrEmpty($Name)) {
        return ""
    }
    $firstChar = $Name[0].ToString().ToLower()
    $translitMap = @{
        'а' = 'a'; 'б' = 'b'; 'в' = 'v'; 'г' = 'g'; 'д' = 'd'; 'е' = 'e'; 'ё' = 'e';
        'ж' = 'zh'; 'з' = 'z'; 'и' = 'i'; 'й' = 'i'; 'к' = 'k'; 'л' = 'l'; 'м' = 'm';
        'н' = 'n'; 'о' = 'o'; 'п' = 'p'; 'р' = 'r'; 'с' = 's'; 'т' = 't'; 'у' = 'u';
        'ф' = 'f'; 'х' = 'kh'; 'ц' = 'ts'; 'ч' = 'ch'; 'ш' = 'sh'; 'щ' = 'shch';
        'ы' = 'y'; 'ъ' = 'ie'; 'э' = 'e'; 'ю' = 'iu'; 'я' = 'ia'
    }
    if ($translitMap.ContainsKey($firstChar)) {
        return $translitMap[$firstChar]
    } else {
        return $firstChar
    }
}


# Основной скрипт
Write-Host "Введите список пользователей в формате 'Фамилия Имя Отчество', разделяя их запятыми:"
$userList = Read-Host

# Разделяем ввод на отдельных пользователей
$users = $userList -split ',' | ForEach-Object { $_.Trim() }

# Загрузка паролей и фраз из файла
$passwordsFile = "C:\Users\PIA.MEDKHV\Desktop\user_script\passwords.txt"
if (-not (Test-Path $passwordsFile)) {
    Write-Host "Файл с паролями не найден: $passwordsFile"
    exit
}
$passwords = Get-Content -Path $passwordsFile

# Проверка, что количество паролей совпадает с количеством пользователей
if ($passwords.Count -lt $users.Count) {
    Write-Host "Ошибка: Недостаточно паролей в файле."
    exit
}

# Выбор подразделения
$selectedOU = Select-OU
if (-not $selectedOU) {
    Write-Host "Подразделение не выбрано. Выход."
    exit
}

# Создание или обновление пользователей
foreach ($user in $users) {
    $parts = $user -split ' '
    if ($parts.Count -ne 3) {
        Write-Host "Ошибка: Неверный формат для пользователя '$user'. Требуется 'Фамилия Имя Отчество'."
        continue
    }

    $LastName = $parts[0]
    $FirstName = $parts[1]
    $MiddleName = $parts[2]

    # Генерация логина
    $SamAccountName = Generate-Username -FirstName $FirstName -LastName $LastName -MiddleName $MiddleName
    $UserPrincipalName = "$SamAccountName@medkhv.ru"
    $DisplayName = "$LastName $FirstName $MiddleName"

    # Получаем случайный пароль и фразу
    $randomIndex = Get-Random -Minimum 0 -Maximum $passwords.Count
    $passwordEntry = $passwords[$randomIndex] -split "`t"
    $Password = $passwordEntry[0]
    $Phrase = $passwordEntry[1]

    # Поиск существующего пользователя
    $existingUser = Find-User -LastName $LastName -FirstName $FirstName -MiddleName $MiddleName -OU $selectedOU

    if ($existingUser) {
        Write-Host "Пользователь '$LastName $FirstName $MiddleName' уже существует."
        $resetPassword = Read-Host "Сбросить пароль? (да/нет)"
        if ($resetPassword -eq 'да') {
            Set-ADAccountPassword -Identity $existingUser.SamAccountName -NewPassword (ConvertTo-SecureString $Password -AsPlainText -Force)
            Set-ADUser -Identity $existingUser.SamAccountName -CannotChangePassword $true -PasswordNeverExpires $true
            Write-Host "Пароль сброшен и настройки учетной записи обновлены."
            Write-Host "$LastName $FirstName $MiddleName"
            Write-Host "Логин - $($existingUser.SamAccountName)"  # Изменено на получение SamAccountName из объекта $existingUser
            Write-Host "Пароль - $Password"
            Write-Host "Фраза - $Phrase"
            Write-Host "-------------------------"
        }
    } else {
        # Если пользователь не найден, создаем нового
        try {
            New-ADUser `
                -Name $DisplayName `
                -GivenName $FirstName `
                -Surname $LastName `
                -SamAccountName $SamAccountName `
                -UserPrincipalName $UserPrincipalName `
                -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
                -Enabled $true `
                -Path $selectedOU `
                -CannotChangePassword $true `
                -PasswordNeverExpires $true `
                -DisplayName $DisplayName

            Write-Host "$LastName $FirstName $MiddleName"
            Write-Host "Логин - $SamAccountName"
            Write-Host "Пароль - $Password"
            Write-Host "Фраза - $Phrase"
            Write-Host "-------------------------"
        } catch {
            Write-Host "Ошибка при создании пользователя ${SamAccountName}: $_"
        }
    }
}
