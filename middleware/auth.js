const db = require('../db');

module.exports = function auth(allowedAuthLevels) {
    return async function (req, res, next) {
        const { userId } = req.query;

        if (!userId) {
            return res.status(401).send('Not Authorized');
        }

        const [[user]] = await db.execute('SELECT * FROM auth_users WHERE id=?', [userId]);

        if (!user) {
            return res.status(401).send('Not Authorized');
        }

        if (!allowedAuthLevels.includes(user.auth_level)) {
            return res.status(401).send('You do not have permission for this resource');
        }

        req.user = user;
        next();
    }
}
