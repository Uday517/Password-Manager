module com.passwordmanager {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.sql;
    requires org.xerial.sqlitejdbc;

    opens com.passwordmanager to javafx.fxml;
    opens com.passwordmanager.controllers to javafx.fxml;
    opens com.passwordmanager.models to javafx.base;
}
