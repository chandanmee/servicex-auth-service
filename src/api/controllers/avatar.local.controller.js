const User = require('../../models/UserCredential');
const path = require('path');

exports.uploadLocal = async (req, res, next) => {
  try {
    const actor = req.user && req.user.sub;
    const userId = req.params.id;
    if (actor !== userId && !(req.user.roles || []).includes('admin')) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    if (!req.file) return res.status(400).json({ message: 'file required' });

    const file = req.file;
    const url = `${req.protocol}://${req.get('host')}/uploads/${file.filename}`; // make sure static route exists

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // optionally delete previous file (implement if desired)
    const prev = user.avatar && user.avatar.key;
    user.avatar = {
      url,
      key: file.filename,
      mimeType: file.mimetype,
      size: file.size,
      uploadedAt: new Date()
    };
    user.updatedBy = actor || user.updatedBy;
    await user.save();

    return res.json({ avatar: user.avatar });
  } catch (err) { next(err); }
};
