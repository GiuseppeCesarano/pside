pub const Task = opaque {
    pub fn get(_: *Task) void {}
    pub fn put(_: *Task) void {}
};

pub const preempt = struct {
    pub fn disable() void {}
    pub fn enable() void {}
};
