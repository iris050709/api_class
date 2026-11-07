import { Router } from "express";
import { createAuthController } from "../controllers/authController";
import { requireAuth, requireUser } from "../middleware/auth";
import type { AuthService } from "../services/authService";

export function createAuthRouter(
  authService: AuthService,
): Router {
  const router = Router();

  const controller = createAuthController(authService);
  const auth = requireAuth(authService);

  // Iniciar sesión.
  router.post("/login", controller.login);
  
  // Registro público de administradores.
  router.post("/register", controller.register);

  // Crear otro administrador.
  router.post(
    "/users",
    auth,
    requireUser,
    controller.register,
  );

  // Renovar tokens.
  router.post("/refresh", controller.refresh);

  // Cerrar sesión.
  router.post(
    "/logout",
    auth,
    controller.logout,
  );

  // Consultar perfil.
  router.get(
    "/me",
    auth,
    controller.me,
  );

  return router;
}