import java.io.ObjectInputStream;

final class Service {
    Object restore(ObjectInputStream input) throws Exception {
        return input.readObject();
    }
}
