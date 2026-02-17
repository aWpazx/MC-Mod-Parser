import type { UnifiedMod, UnifiedFile } from './api';

export interface SavedMod extends UnifiedMod {
  selectedFile?: UnifiedFile;
  savedAt: string;
}

export interface UserAccount {
  id: string;
  email: string;
  username: string;
  passwordHash: string;
  createdAt: string;
  cfApiKey: string;
  savedMods: SavedMod[];
}

const USERS_KEY = 'xvoldata_users';
const CURRENT_USER_KEY = 'xvoldata_current_user';

// Простое хеширование пароля (для демонстрации)
// В реальном приложении используйте bcrypt или подобное
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Получить всех пользователей
function getAllUsers(): UserAccount[] {
  const usersJson = localStorage.getItem(USERS_KEY);
  return usersJson ? JSON.parse(usersJson) : [];
}

// Сохранить всех пользователей
function saveAllUsers(users: UserAccount[]): void {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

// Проверка надежности пароля
export function validatePassword(password: string): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Минимум 8 символов');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Хотя бы одна заглавная буква');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Хотя бы одна строчная буква');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Хотя бы одна цифра');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}

// Проверка email
function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Регистрация
export async function register(
  emailOrUsername: string,
  password: string
): Promise<{ success: boolean; error?: string; user?: UserAccount }> {
  const users = getAllUsers();
  
  // Проверка пароля
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.isValid) {
    return { success: false, error: passwordValidation.errors.join('. ') };
  }
  
  // Определить, это email или username
  const isEmail = validateEmail(emailOrUsername);
  const email = isEmail ? emailOrUsername : '';
  const username = isEmail ? emailOrUsername.split('@')[0] : emailOrUsername;
  
  // Проверить, существует ли пользователь
  const existingUser = users.find(
    u => u.email === email || u.username === username
  );
  
  if (existingUser) {
    return { success: false, error: 'Пользователь с таким email или логином уже существует' };
  }
  
  // Создать нового пользователя
  const passwordHash = await hashPassword(password);
  const newUser: UserAccount = {
    id: crypto.randomUUID(),
    email,
    username,
    passwordHash,
    createdAt: new Date().toISOString(),
    cfApiKey: '',
    savedMods: [],
  };
  
  users.push(newUser);
  saveAllUsers(users);
  
  // Автоматический вход
  localStorage.setItem(CURRENT_USER_KEY, newUser.id);
  
  return { success: true, user: newUser };
}

// Вход
export async function login(
  emailOrUsername: string,
  password: string
): Promise<{ success: boolean; error?: string; user?: UserAccount }> {
  const users = getAllUsers();
  const passwordHash = await hashPassword(password);
  
  // Найти пользователя по email или username
  const user = users.find(
    u => (u.email === emailOrUsername || u.username === emailOrUsername) && u.passwordHash === passwordHash
  );
  
  if (!user) {
    return { success: false, error: 'Неверный логин или пароль' };
  }
  
  // Сохранить текущего пользователя
  localStorage.setItem(CURRENT_USER_KEY, user.id);
  
  return { success: true, user };
}

// Выход
export function logout(): void {
  localStorage.removeItem(CURRENT_USER_KEY);
}

// Получить текущего пользователя
export function getCurrentUser(): UserAccount | null {
  const userId = localStorage.getItem(CURRENT_USER_KEY);
  if (!userId) return null;
  
  const users = getAllUsers();
  return users.find(u => u.id === userId) || null;
}

// Обновить данные пользователя
export function updateUser(userId: string, updates: Partial<UserAccount>): boolean {
  const users = getAllUsers();
  const userIndex = users.findIndex(u => u.id === userId);
  
  if (userIndex === -1) return false;
  
  users[userIndex] = { ...users[userIndex], ...updates };
  saveAllUsers(users);
  
  return true;
}

// Сохранить моды
export function saveMods(userId: string, mods: SavedMod[]): boolean {
  return updateUser(userId, { savedMods: mods });
}

// Сохранить API ключ
export function saveCfApiKey(userId: string, apiKey: string): boolean {
  return updateUser(userId, { cfApiKey: apiKey });
}

// Восстановление пароля (эмуляция)
export function requestPasswordReset(emailOrUsername: string): { success: boolean; message: string } {
  const users = getAllUsers();
  const user = users.find(u => u.email === emailOrUsername || u.username === emailOrUsername);
  
  if (!user) {
    return { 
      success: false, 
      message: 'Пользователь не найден' 
    };
  }
  
  // В реальном приложении здесь была бы отправка email
  // Для демонстрации просто возвращаем успех
  return { 
    success: true, 
    message: `Инструкции по восстановлению пароля отправлены на ${user.email || 'ваш email'}` 
  };
}
