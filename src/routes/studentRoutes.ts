import { Router } from "express";
import { createStudentController } from "../controllers/studentController";
import { requireAuth, requireUser } from "../middleware/auth";
import type { AuthService } from "../services/authService";
import type { StudentRepository } from "../repositories/studentRepository";

/** Todas las rutas de estudiantes están protegidas por JWT. */
export function createStudentRouter(
  students: StudentRepository,
  authService: AuthService,
): Router {
  const router = Router();
  const controller = createStudentController(students);
  const auth = requireAuth(authService);
  const admin = requireUser;

  // Todas las operaciones requieren una cuenta de tipo user.
  router.post("/", auth, admin, controller.create);
  router.get("/", auth, admin, controller.list);
  router.get("/:id", auth, admin, controller.getOne);
  router.put("/:id", auth, admin, controller.update);
  router.delete("/:id", auth, admin, controller.remove);

  return router;
}
