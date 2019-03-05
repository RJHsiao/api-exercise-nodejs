const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SessionSchema = new Schema({
  sessionKey: {type: String, required: true, index: true, unique: true},
  userId: {type: Schema.Types.ObjectId, required: true},
  expiredAt: {type: Date, default: () => Date.now() + 7*24*60*60*1000},
});

sessionModel = mongoose.model('Session', SessionSchema);

module.exports = sessionModel;