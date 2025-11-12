import { Router } from 'express';
import { createLoginHistory, listLoginHistories } from './controller';
import { protect } from '../../middlewares/auth';

const router = Router();
router.get('/', protect, listLoginHistories);
router.post('/', protect, createLoginHistory);
export default router;
