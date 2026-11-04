
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

  // Registro de usuarios: solamente administradores.
  router.post(
    "/register",
    auth,
    requireUser,
    controller.register,
  );

  // Crear otro usuario administrador desde la aplicación.
  router.post(
    "/users",
    auth,
    requireUser,
    controller.register,
  );

  // Inicio de sesión.
  router.post("/login", controller.login);

  // Renovación de tokens.
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
