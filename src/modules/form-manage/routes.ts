import { Router } from 'express'
import {
    createOrUpdateFormManager,
    listFormManagers,
    deleteFormManager,
    getFormManagerByInstituteId
} from './controller'
import { protect } from '../../middlewares/auth'
const router = Router()
router.get('/', protect, listFormManagers)
router.post('/', protect, createOrUpdateFormManager)
router.get('/:instituteId', protect, getFormManagerByInstituteId)
router.delete('/:id', protect, deleteFormManager)

export default router
