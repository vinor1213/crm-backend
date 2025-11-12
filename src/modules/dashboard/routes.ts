import { Router } from 'express';
import {  dashboardData,  } from './controller';
import { protect } from '../../middlewares/auth';
const router = Router();
router.get('/', protect, dashboardData);

export default router;
