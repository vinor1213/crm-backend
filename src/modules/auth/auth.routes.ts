import { Router } from 'express';
import {
    register, login, listUsers, updateUser,
    deleteUser, changePasswordwithotpverfiedperson, changePassword
} from './auth.controller';
import { protect } from '../../middlewares/auth';

const router = Router();

router.post('/register', protect, register);
router.post('/login', login);
router.get("/users", protect, listUsers);
router.put("/:id", protect, updateUser);
router.delete("/:id", protect, deleteUser);
router.post("/changenewpasswordvialogin", protect, changePassword);
router.post("/changenewpassword", changePasswordwithotpverfiedperson);


export default router;
