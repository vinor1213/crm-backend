import { Router } from 'express';
import {
  upsertSettings,
  getSettingsByInstitute,
  getAllSettings,
  deleteSettings,
} from './controller';
import { protect } from '../../middlewares/auth';

const router = Router();

router.post('/', protect, upsertSettings);


router.get('/:instituteId', protect, getSettingsByInstitute);


router.get('/', protect, getAllSettings);


router.delete('/:instituteId', protect, deleteSettings);

export default router;
