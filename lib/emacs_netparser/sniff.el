(add-to-list 'load-path "~/work/pi/netparser/target/debug/")
(require 'emacs_netparser)

(defvar netparse/temp-file-dir (expand-file-name ".netparse/" user-emacs-directory))

(defun netparse/setup ()
  "Initialize netparse variables and create temporary storage directory."
  (make-directory netparse/temp-file-dir t))

(defun format-row (packets &optional format-face)
  (or format-face (setq format-face 'font-lock-warning-face))
  (let* ((format-string (format "%s %s %s\n"
				(cdr (assoc "MAC" packets))
				(cdr (assoc "IP" packets))
				(cdr (assoc "PORT" packets)))))
    (put-text-property 0 (length format-string) 'font-lock-face format-face format-string)
    (insert format-string)))

(defun align-repeat()
  (align-regexp (point-min)
		(point-max)
		(concat "\\(\\s-*\\)" "[[:space:]]+") 1 1 t))

(defun filter-by-mac (packets)
  (sort packets (lambda (a b) (string< (car a) (car b)))))

(setq header-list '(("MAC" . "MAC")
		    ("IP" . "IP")
		    ("PORT" . "PORT"))
      packet-list '(("MAC" . "0x1234")
		    ("IP" . "0.0.0.0")
		    ("PORT" . ":1234")))

(let ((temp-buf-name "*Sniff My Packets*"))
  (get-buffer-create temp-buf-name)
  (switch-to-buffer-other-window temp-buf-name)
  (special-mode)
  (let ((inhibit-read-only t))
    (format-row header-list)
    (format-row packet-list 'font-lock-constant-face)
    (align-repeat)))
