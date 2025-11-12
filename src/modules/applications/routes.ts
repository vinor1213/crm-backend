import { Router } from 'express'
import {
    createApplication,
    listApplications,
    getApplication,
    updateApplication,
    deleteApplication,
    updatePaymentStatus,
    listpendingApplications,
    sendmail
} from './controller'
import { protect } from '../../middlewares/auth'
import { upload } from "./multerConfig";

const router = Router()

router.post("/", protect, upload.any(), createApplication);
router.get('/', protect, listApplications)

router.get("/pending-applications", protect, listpendingApplications);
router.get('/:id', protect, getApplication)

router.put("/:id", protect, upload.any(), updateApplication);
router.patch("/:id/payment-status", protect, updatePaymentStatus);
router.delete('/:id', protect, deleteApplication)
router.post("/send-mail", protect, sendmail);

export default router
