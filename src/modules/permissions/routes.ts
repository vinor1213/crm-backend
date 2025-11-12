import { Router } from "express";
import {
    createOrUpdatePermission,
    getPermissions,
    deletePermission,
    getPermissionsforusers
} from "./controller";
import { protect } from "../../middlewares/auth"; 

const router = Router();


router.post("/", protect, createOrUpdatePermission);


router.get("/", protect, getPermissions);

router.get("/getaccesscontrol", protect, getPermissionsforusers);

router.delete("/:id", protect, deletePermission);

export default router;
