module.exports = (req, errorValue) => {
  let message = req.flash(errorValue);
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  return message;
}